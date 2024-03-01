rule ESET_Keydnap_Downloader
{
	meta:
		description = "OSX/Keydnap Downloader"
		author = "Marc-Etienne M.Léveillé"
		id = "2b21007a-b143-5538-8777-ba35448d00aa"
		date = "2016-07-06"
		modified = "2016-07-06"
		reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/keydnap/keydnap.yar#L33-L49"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "71c8885193a92fa9c71055c37e629a54d50070cf6820b9216a824ecc4db2ce3c"
		score = 75
		quality = 80
		tags = ""
		version = "1"

	strings:
		$ = "icloudsyncd"
		$ = "killall Terminal"
		$ = "open %s"

	condition:
		2 of them
}
