import "pe"

rule SIGNATURE_BASE_HKTL_Amplia_Security_Tool : FILE
{
	meta:
		description = "Detects Amplia Security Tool like Windows Credential Editor"
		author = "Florian Roth"
		id = "4ad83f34-561d-53ce-9766-e21700354da7"
		date = "2013-01-01"
		modified = "2023-02-14"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L34-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7ca32d8df0011f23922c6566b28aa55b0756d5b67bf3db8908b206b1038bb1f2"
		score = 60
		quality = 85
		tags = "FILE"
		nodeepdive = 1

	strings:
		$a = "Amplia Security"
		$c = "getlsasrvaddr.exe"
		$d = "Cannot get PID of LSASS.EXE"
		$e = "extract the TGT session key"
		$f = "PPWDUMP_DATA"

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and (2 of them ) or 3 of them
}
