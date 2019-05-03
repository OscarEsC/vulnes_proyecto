main:
	chmod 755 cms_scanner.py
	ln -rs cms_analizer.py /usr/bin/cms_scanner

clean:
	rm /usr/bin/cms_scanner
