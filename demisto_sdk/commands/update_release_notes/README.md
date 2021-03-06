## Update Release Notes

**Automatically identify and create a release notes template for changed items.**

### Use Cases
This command is used in order to create or update release notes for a new pack version. The command will also automatically bump the `currentVersion` found in the `pack_metadata.json` file.

Supported content entities:
- Integrations
- Playbooks
- Scripts
- Widgets
- Dashboards
- Incident Types
- Incident Fields
- Layouts
- Classifiers

### Arguments
* **-p, --pack <PACK_NAME>**

    The name of the pack you wish to generate release notes for.

* **-u, --update_type**

    Optional. If no update_type is defined, the `currentVersion` will not be bumped.

    The type of update being done. Available options are:
    - major
    - minor
    - revision

* **--all**

    Update all release notes in every pack which has been changed. Please note that the `-u` argument will be applied to **all** changed packs.

* **--pre_release**

    Indicates that this update is for a pre-release version. The `currentVersion` will change to reflect the pre-release version number.

### Examples
```
demisto-sdk update-release-notes -p HelloWorld -u minor
```
This will create a new markdown file in the `ReleaseNotes` folder for the HelloWorld pack and bump the `currentVersion` with a **minor** increment.
<br/><br/>
```
demisto-sdk update-release-notes -p HelloWorld -u major
```
This will create a new markdown file in the `ReleaseNotes` folder for the HelloWorld pack and bump the `currentVersion` with a **major** increment.
<br/><br/>
```
demisto-sdk update-release-notes -p HelloWorld -u revision
```
This will create a new markdown file in the `ReleaseNotes` folder for the HelloWorld pack and bump the `currentVersion` with a **revision** increment.
<br/><br/>
```
demisto-sdk update-release-notes --all -u revision
```
This will create a new markdown file in the `ReleaseNotes` folder for **all** changed packs and bump the `currentVersion` for **all** changed packs with a **revision** increment.
<br/><br/>

```
demisto-sdk update-release-notes -p HelloWorld -u revision --pre_release
```
This will create a new markdown file in the `ReleaseNotes` folder for the HellWorld pack and bump the `currentVersion` with a **revision** increment as well as append `pre_release` to the `currentVersion`.
