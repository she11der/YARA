rule ESET_Keydnap_Backdoor
{
	meta:
		description = "Unpacked OSX/Keydnap backdoor"
		author = "Marc-Etienne M.Léveillé"
		id = "099c1796-6237-5ec1-ba25-cd5feca79865"
		date = "2016-07-06"
		modified = "2016-07-06"
		reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/keydnap/keydnap.yar#L69-L86"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "fa209577a562ef9088d3ad3df3fbc0edda96f09d19177842f0ddea42c658f530"
		score = 75
		quality = 80
		tags = ""
		version = "1"

	strings:
		$ = "api/osx/get_task"
		$ = "api/osx/cmd_executed"
		$ = "Loader-"
		$ = "u2RLhh+!LGd9p8!ZtuKcN"
		$ = "com.apple.iCloud.sync.daemon"

	condition:
		2 of them
}
