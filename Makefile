main:
	chmod 755 cms_analizer.py
	ln -rs cms_analizer.py /usr/bin/cms_analizer

clean:
	rm /usr/bin/cms_analizer
