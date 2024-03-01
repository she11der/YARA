import "pe"

rule SIGNATURE_BASE_Remcom_Remotecommandexecution
{
	meta:
		description = "Detects strings from RemCom tool"
		author = "Florian Roth (Nextron Systems)"
		id = "90b4ce3c-a690-5b6e-95e8-7e5dc8270152"
		date = "2017-12-28"
		modified = "2023-12-05"
		reference = "https://goo.gl/tezXZt"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L4122-L4137"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c39a09c8d0c1799febcb4d9eafece43f8b21e7ffc277fdfad6c235eb1a201697"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$ = "\\\\.\\pipe\\%s%s%d"
		$ = "%s\\pipe\\%s%s%d%s"
		$ = "\\ADMIN$\\System32\\%s%s"

	condition:
		1 of them
}
