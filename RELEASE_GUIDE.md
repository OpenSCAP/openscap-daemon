# Release guide for OpenSCAP daemon

* change version name in openscap_daemon/version.py
* commit the change with message "Version bumped to $version"
* git push
* git tag $version
* git push --tags
* python setup.py sdist
* tarball will be generated in dist directory
* check the tarball whether it contains all the files
* upload the tarball to github
