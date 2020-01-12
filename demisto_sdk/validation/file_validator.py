"""
This script is used to validate the files in Content repository. Specifically for each file:
1) Proper prefix
2) Proper suffix
3) Valid yml/json schema
4) Having ReleaseNotes if applicable.

It can be run to check only committed changes (if the first argument is 'true') or all the files in the repo.
Note - if it is run for all the files in the repo it won't check releaseNotes, use `release_notes.py`
for that task.
"""
from __future__ import print_function

import os
import re
import glob
from inspect import signature

from demisto_sdk.common.hook_validations.pack_unique_files import PackUniqueFilesValidator
from demisto_sdk.common.configuration import Configuration
from demisto_sdk.common.constants import CODE_FILES_REGEX, OLD_YML_FORMAT_FILE, SCHEMA_REGEX, KNOWN_FILE_STATUSES, \
    IGNORED_TYPES_REGEXES, INTEGRATION_REGEX, IMAGE_REGEX, TEST_PLAYBOOK_REGEX, DIR_LIST_FOR_REGULAR_ENTETIES, \
    PACKAGE_SUPPORTING_DIRECTORIES, YML_BETA_INTEGRATIONS_REGEXES, SCRIPT_REGEXES, YML_INTEGRATION_REGEXES, \
    PACKS_DIR, PACKS_DIRECTORIES, Errors, PLAYBOOKS_REGEXES_LIST, JSON_INDICATOR_AND_INCIDENT_FIELDS, \
    JSON_ALL_LAYOUT_REGEXES, REPUTATION_REGEX, SCRIPT_REGEX
from demisto_sdk.common.hook_validations.conf_json import ConfJsonValidator
from demisto_sdk.common.hook_validations.id import IDSetValidator
from demisto_sdk.common.hook_validations.image import ImageValidator
from demisto_sdk.common.hook_validations.incident_field import IncidentFieldValidator
from demisto_sdk.common.hook_validations.integration import IntegrationValidator
from demisto_sdk.common.hook_validations.script import ScriptValidator
from demisto_sdk.common.hook_validations.structure import StructureValidator
from demisto_sdk.common.hook_validations.playbook import PlaybookValidator
from demisto_sdk.common.hook_validations.layout import LayoutValidator

from demisto_sdk.common.tools import checked_type, run_command, print_error, print_warning, print_color, \
    LOG_COLORS, get_yaml, filter_packagify_changes, get_pack_name, is_file_path_in_pack, \
    get_yml_paths_in_dir
from demisto_sdk.common.hook_validations.release_notes import ReleaseNotesValidator


class FilesValidator:
    """FilesValidator is a class that's designed to validate all the changed files on your branch, and all files in case
    you are on master, this class will be used on your local env as the validation hook(pre-commit), and on CircleCi
    to make sure you did not bypass the hooks as a safety precaution.

    Attributes:
        is_backward_check (bool): Whether to check for backwards compatibility.
        prev_ver (str): If using git, holds the branch to compare the current one to. Default is origin/master.
        use_git (bool): Whether to use git or not.
        is_circle: (bool): Whether the validation was initiated by CircleCI or not.
        print_ignored_files (bool): Whether to print the files that were ignored during the validation or not.
        validate_conf_json (bool): Whether to validate conf.json or not.
        validate_id_set (bool): Whether to validate id_set or not.
        file_path (string): If validating a specific file, golds it's path.
        configuration (Configuration): Configurations for IDSetValidator.
    """

    def __init__(self, is_backward_check=True, prev_ver='origin/master', use_git=False, is_circle=False,
                 print_ignored_files=False, validate_conf_json=True, validate_id_set=False, file_path=None,
                 configuration=Configuration()):
        self.branch_name = ''
        self.use_git = use_git
        if self.use_git:
            print('Using git')
            self.branch_name = self.get_current_working_branch()
            print(f'Running validation on branch {self.branch_name}')

        self.prev_ver = prev_ver
        if not self.prev_ver:
            # validate against master if no version was provided
            self.prev_ver = 'origin/master'

        self._is_valid = True
        self.configuration = configuration
        self.is_backward_check = is_backward_check
        self.is_circle = is_circle
        self.print_ignored_files = print_ignored_files
        self.validate_conf_json = validate_conf_json
        self.validate_id_set = validate_id_set
        self.file_path = file_path

        if self.validate_conf_json:
            self.conf_json_validator = ConfJsonValidator()
        if self.validate_id_set:
            self.id_set_validator = IDSetValidator(is_circle=self.is_circle, configuration=self.configuration)

    def run(self):
        print_color('Starting validating files structure', LOG_COLORS.GREEN)
        if self.is_valid_structure():
            print_color('The files are valid', LOG_COLORS.GREEN)
            return 0
        else:
            print_color('The files were found as invalid, the exact error message can be located above', LOG_COLORS.RED)
            return 1

    @staticmethod
    def get_current_working_branch():
        branches = run_command('git branch')
        branch_name_reg = re.search(r'\* (.*)', branches)
        return branch_name_reg.group(1)

    @staticmethod
    def get_modified_files(files_string, tag='master', print_ignored_files=False):
        """Get lists of the modified files in your branch according to the files string.

        Args:
            files_string (string): String that was calculated by git using `git diff` command.
            tag (string): String of git tag used to update modified files.
            print_ignored_files (bool): should print ignored files.

        Returns:
            (modified_files_list, added_files_list, deleted_files). Tuple of sets.
        """
        all_files = files_string.split('\n')
        deleted_files = set([])
        added_files_list = set([])
        modified_files_list = set([])
        old_format_files = set([])
        for f in all_files:
            file_data = f.split()
            if not file_data:
                continue

            file_status = file_data[0]
            file_path = file_data[1]

            if file_status.lower().startswith('r'):
                file_status = 'r'
                file_path = file_data[2]

            if checked_type(file_path, CODE_FILES_REGEX) and file_status.lower() != 'd' \
                    and not file_path.endswith('_test.py'):
                # naming convention - code file and yml file in packages must have same name.
                file_path = os.path.splitext(file_path)[0] + '.yml'
            elif file_path.endswith('.js') or file_path.endswith('.py'):
                continue

            if file_status.lower() in ['m', 'a', 'r'] and checked_type(file_path, OLD_YML_FORMAT_FILE) and \
                    FilesValidator._is_py_script_or_integration(file_path):
                old_format_files.add(file_path)
            elif file_status.lower() == 'm' and checked_type(file_path) and not file_path.startswith('.'):
                modified_files_list.add(file_path)
            elif file_status.lower() == 'a' and checked_type(file_path) and not file_path.startswith('.'):
                added_files_list.add(file_path)
            elif file_status.lower() == 'd' and checked_type(file_path) and not file_path.startswith('.'):
                deleted_files.add(file_path)
            elif file_status.lower().startswith('r') and checked_type(file_path):
                # if a code file changed, take the associated yml file.
                if checked_type(file_data[2], CODE_FILES_REGEX):
                    modified_files_list.add(file_path)
                else:
                    modified_files_list.add((file_data[1], file_data[2]))

            elif checked_type(file_path, [SCHEMA_REGEX]):
                modified_files_list.add(file_path)

            elif file_status.lower() not in KNOWN_FILE_STATUSES:
                print_error('{} file status is an unknown one, please check. File status was: {}'
                            .format(file_path, file_status))

            elif print_ignored_files and not checked_type(file_path, IGNORED_TYPES_REGEXES):
                print_warning('Ignoring file path: {}'.format(file_path))

        modified_files_list, added_files_list, deleted_files = filter_packagify_changes(
            modified_files_list,
            added_files_list,
            deleted_files,
            tag)

        return modified_files_list, added_files_list, deleted_files, old_format_files

    def get_modified_and_added_files(self, tag='origin/master'):
        """Get lists of the modified and added files in your branch according to the git diff output.

        Args:
            tag (string): String of git tag used to update modified files

        Returns:
            (modified_files, added_files). Tuple of sets.
        """
        # Two dots is the default in git diff, it will compare with the last known commit as the base
        # Three dots will compare with the last known shared commit as the base
        compare_type = '.' if 'master' in tag else ''
        all_changed_files_string = run_command(
            'git diff --name-status {tag}..{compare_type}refs/heads/{branch}'.format(tag=tag,
                                                                                     branch=self.branch_name,
                                                                                     compare_type=compare_type))

        modified_files, added_files, _, old_format_files = self.get_modified_files(
            all_changed_files_string,
            tag=tag,
            print_ignored_files=self.print_ignored_files)

        if not self.is_circle:
            files_string = run_command('git diff --name-status --no-merges HEAD')
            nc_modified_files, nc_added_files, nc_deleted_files, nc_old_format_files = self.get_modified_files(
                files_string, print_ignored_files=self.print_ignored_files)

            all_changed_files_string = run_command('git diff --name-status {}'.format(tag))
            modified_files_from_tag, added_files_from_tag, _, _ = \
                self.get_modified_files(all_changed_files_string,
                                        print_ignored_files=self.print_ignored_files)

            if self.file_path:
                if os.path.isdir(self.file_path):
                    yml_files_in_package = glob.glob(os.path.join(self.file_path, '*.yml'))
                    if yml_files_in_package:
                        self.file_path = yml_files_in_package[0]

                    else:
                        raise Exception(f"The path provided {self.file_path} is not an integration/script package, "
                                        f"nor a specific file.")

                if F'M\t{self.file_path}' in files_string:
                    modified_files = {self.file_path}
                    added_files = set()
                else:
                    modified_files = set()
                    added_files = {self.file_path}
                return modified_files, added_files, set(), set()

            old_format_files = old_format_files.union(nc_old_format_files)
            modified_files = modified_files.union(
                modified_files_from_tag.intersection(nc_modified_files))

            added_files = added_files.union(
                added_files_from_tag.intersection(nc_added_files))

            modified_files = modified_files - set(nc_deleted_files)
            added_files = added_files - set(nc_modified_files) - set(nc_deleted_files)

        packs = self.get_packs(modified_files, added_files)

        return modified_files, added_files, old_format_files, packs

    @staticmethod
    def get_packs(modified_files, added_files):
        packs = set()
        changed_files = modified_files.union(added_files)
        for changed_file in changed_files:
            if isinstance(changed_file, tuple):
                changed_file = changed_file[1]
            pack = get_pack_name(changed_file)
            if pack and is_file_path_in_pack(changed_file):
                packs.add(pack)

        return packs

    def is_valid_release_notes(self, file_path):
        release_notes_validator = ReleaseNotesValidator(file_path)
        if not release_notes_validator.is_file_valid():
            self._is_valid = False

    def validate_files(self, affected_files, is_added=False):
        REGEX_TO_VALIDATOR = {
            TEST_PLAYBOOK_REGEX: lambda x: print('Not validating Test playbook'),
            tuple(YML_INTEGRATION_REGEXES): self.validate_integration_yml,
            tuple(YML_BETA_INTEGRATIONS_REGEXES): self.validate_beta_integration,
            IMAGE_REGEX: self.validate_image,
            REPUTATION_REGEX: self.validate_reputation_file,
            tuple(SCRIPT_REGEXES): self.validate_script,
            tuple(PLAYBOOKS_REGEXES_LIST): self.validate_playbook,
            tuple(JSON_INDICATOR_AND_INCIDENT_FIELDS): self.validate_indicator_and_incident_fields,
            tuple(JSON_ALL_LAYOUT_REGEXES): self.validate_layout,
            # Classifiers
            # Dashboards
            # Incident types
            # reports
        }

        for file_path in affected_files:
            print('Validating {}'.format(file_path))

            if 'CHANGELOG' in file_path:
                self.is_valid_release_notes(file_path)
                continue

            matched_regex = checked_type(file_path if not isinstance(file_path, tuple) else file_path[1],
                                         return_regex=True)
            if not matched_regex:
                print_warning('- Skipping validation of non-content entity file.')
                continue

            self.validate_id_set_data(file_path, is_added)
            for key in REGEX_TO_VALIDATOR:
                if matched_regex in key:
                    if 'is_added' in signature(REGEX_TO_VALIDATOR[key]).parameters.keys():
                        REGEX_TO_VALIDATOR[key](file_path=file_path,
                                                is_added=is_added)
                    else:
                        REGEX_TO_VALIDATOR[key](file_path=file_path)

                    break

            else:
                print(f"The file {file_path} doesn't have a validation.")
                self._is_valid = False

    def validate_no_old_format(self, old_format_files):
        """ Validate there are no files in the old format(unified yml file for the code and configuration).

        Args:
            old_format_files(set): file names which are in the old format.
        """
        invalid_files = []
        for f in old_format_files:
            yaml_data = get_yaml(f)
            if 'toversion' not in yaml_data:  # we only fail on old format if no toversion (meaning it is latest)
                invalid_files.append(f)
        if invalid_files:
            print_error('You should update the following files to the package format, for further details please visit '
                        'https://github.com/demisto/content/tree/master/docs/package_directory_structure. '
                        'The files are:\n{}'.format('\n'.join(list(invalid_files))))
            self._is_valid = False

    def validate_committed_files(self):
        """Validate that all the committed files in your branch are valid"""
        modified_files, added_files, old_format_files, packs = self.get_modified_and_added_files()
        schema_changed = False
        for f in modified_files:
            if isinstance(f, tuple):
                _, f = f
            if checked_type(f, [SCHEMA_REGEX]):
                schema_changed = True
        # Ensure schema change did not break BC
        if schema_changed:
            print("Schema changed, validating all files")
            self.validate_all_files()
        else:
            self.validate_files(modified_files)
            self.validate_files(added_files, is_added=True)
            self.validate_no_old_format(old_format_files)
            self.validate_pack_unique_files(packs)

    def validate_pack_unique_files(self, packs):
        for pack in packs:
            pack_unique_files_validator = PackUniqueFilesValidator(pack)
            pack_errors = pack_unique_files_validator.validate_pack_unique_files()
            if pack_errors:
                print_error(pack_errors)
                self._is_valid = False

    def validate_all_files(self):
        """Validate all files in the repo are in the right format."""
        # go over packs
        for root, dirs, _ in os.walk(PACKS_DIR):
            for dir_in_dirs in dirs:
                for directory in PACKS_DIRECTORIES:
                    for inner_root, inner_dirs, files in os.walk(os.path.join(root, dir_in_dirs, directory)):
                        for inner_dir in inner_dirs:
                            if inner_dir.startswith('.'):
                                continue

                            project_dir = os.path.join(inner_root, inner_dir)
                            _, file_path = get_yml_paths_in_dir(os.path.normpath(project_dir),
                                                                Errors.no_yml_file(project_dir))
                            if file_path:
                                print("Validating {}".format(file_path))
                                structure_validator = StructureValidator(file_path)
                                if not structure_validator.is_valid_scheme():
                                    self._is_valid = False

        # go over regular content entities
        for directory in DIR_LIST_FOR_REGULAR_ENTETIES:
            print_color('Validating {} directory:'.format(directory), LOG_COLORS.GREEN)
            for root, dirs, files in os.walk(directory):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    # skipping hidden files
                    if not file_name.endswith('.yml'):
                        continue

                    print('Validating ' + file_name)
                    structure_validator = StructureValidator(file_path)
                    if not structure_validator.is_valid_scheme():
                        self._is_valid = False

        # go over regular PACKAGE_SUPPORTING_DIRECTORIES entities
        for directory in PACKAGE_SUPPORTING_DIRECTORIES:
            for root, dirs, files in os.walk(directory):
                for inner_dir in dirs:
                    if inner_dir.startswith('.'):
                        continue

                    project_dir = os.path.join(root, inner_dir)
                    _, file_path = get_yml_paths_in_dir(project_dir, Errors.no_yml_file(project_dir))
                    if file_path:
                        print('Validating ' + file_path)
                        structure_validator = StructureValidator(file_path)
                        if not structure_validator.is_valid_scheme():
                            self._is_valid = False

    def is_valid_structure(self):
        """Check if the structure is valid for the case we are in, master - all files, branch - changed files.

        Returns:
            (bool). Whether the structure is valid or not.
        """
        if self.validate_conf_json:
            if not self.conf_json_validator.is_valid_conf_json():
                self._is_valid = False
        if self.use_git:
            if self.branch_name != 'master' and (not self.branch_name.startswith('19.') and
                                                 not self.branch_name.startswith('20.')):
                print('Validates only committed files')
                self.validate_committed_files()
                self.validate_against_previous_version(no_error=True)
            else:
                self.validate_against_previous_version(no_error=True)
                print('Validates all of Content repo directories according to their schemas')
                self.validate_all_files()
        else:
            if self.file_path:
                self.branch_name = self.get_current_working_branch()
                self.validate_committed_files()
            else:
                print('Not using git, validating all files')
                self.validate_all_files()

        return self._is_valid

    def validate_against_previous_version(self, no_error=False):
        """Validate all files that were changed between previous version and branch_sha

        Args:
            no_error (bool): If set to true will restore self._is_valid after run (will not return new errors)
        """
        if self.prev_ver and self.prev_ver != 'master':
            print_color('Starting validation against {}'.format(self.prev_ver), LOG_COLORS.GREEN)
            modified_files, _, _, _ = self.get_modified_and_added_files(self.prev_ver)
            prev_self_valid = self._is_valid
            self.validate_files(modified_files)
            if no_error:
                self._is_valid = prev_self_valid

    @staticmethod
    def _is_py_script_or_integration(file_path):
        file_yml = get_yaml(file_path)
        if re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE):
            if file_yml.get('script', {}).get('type', 'javascript') != 'python':
                return False
            return True

        if re.match(SCRIPT_REGEX, file_path, re.IGNORECASE):
            if file_yml.get('type', 'javascript') != 'python':
                return False

            return True

        return False

    def validate_integration_yml(self, file_path, is_added=False):
        structure_validator = StructureValidator(file_path)
        integration_validator = IntegrationValidator(structure_validator)
        if not is_added and self.is_backward_check and not integration_validator.is_backward_compatible():
            self._is_valid = False

        if not integration_validator.is_valid_file(validate_rn=not is_added):
            self._is_valid = False

    def validate_beta_integration(self, file_path):
        structure_validator = StructureValidator(file_path)
        integration_validator = IntegrationValidator(structure_validator)
        if not integration_validator.is_valid_beta_integration():
            self._is_valid = False

    def validate_image(self, file_path):
        image_validator = ImageValidator(file_path)
        if not image_validator.is_valid():
            self._is_valid = False

    def validate_reputation_file(self, file_path):
        print_color(
            F'Skipping validation for file {file_path} since no validation is currently defined.',
            LOG_COLORS.YELLOW)

    def validate_script(self, file_path, is_added=False):
        structure_validator = StructureValidator(file_path)
        script_validator = ScriptValidator(structure_validator)
        if self.is_backward_check and not script_validator.is_backward_compatible():
            self._is_valid = False
        if not script_validator.is_valid_file(validate_rn=not is_added):
            self._is_valid = False

    def validate_playbook(self, file_path, is_added=False):
        structure_validator = StructureValidator(file_path)
        playbook_validator = PlaybookValidator(structure_validator)
        if not playbook_validator.is_valid_playbook(is_new_playbook=is_added):
            self._is_valid = False

    def validate_indicator_and_incident_fields(self, file_path):
        structure_validator = StructureValidator(file_path)
        incident_field_validator = IncidentFieldValidator(structure_validator)
        if not incident_field_validator.is_valid_file():
            self._is_valid = False
        if self.is_backward_check and not incident_field_validator.is_backward_compatible():
            self._is_valid = False

    def validate_layout(self, file_path):
        structure_validator = StructureValidator(file_path)
        layout_validator = LayoutValidator(structure_validator)
        if not layout_validator.is_valid_layout():
            self._is_valid = False

    def validate_id_set_data(self, file_path, is_added=False):
        if self.validate_id_set:
            if not self.id_set_validator.is_file_valid_in_set(file_path):
                self._is_valid = False

            if is_added and self.id_set_validator.is_file_has_used_id(file_path):
                self._is_valid = False
