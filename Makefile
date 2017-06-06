sdist:
	    python setup.py sdist

rpm: sdist
	    rpmbuild -ba openscap-daemon.spec --define "_sourcedir `pwd`/dist"

clean:
	    rm -rf dist 


