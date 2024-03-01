import "pe"

rule SIGNATURE_BASE_Linux_Portscan_Shark_1 : FILE
{
	meta:
		description = "Detects Linux Port Scanner Shark"
		author = "Florian Roth (Nextron Systems)"
		id = "0b264106-3536-56f4-9e8c-68f3756af07d"
		date = "2016-04-01"
		modified = "2023-12-05"
		reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3199-L3216"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e807ed6c83c8d908bfe29c65abd7b877b65655cc64cd1497fc124a2fd88cd1e9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "4da0e535c36c0c52eaa66a5df6e070c52e7ddba13816efc3da5691ea2ec06c18"
		hash2 = "e395ca5f932419a4e6c598cae46f17b56eb7541929cdfb67ef347d9ec814dea3"

	strings:
		$s0 = "rm -rf scan.log session.txt" fullword ascii
		$s17 = "*** buffer overflow detected ***: %s terminated" fullword ascii
		$s18 = "*** stack smashing detected ***: %s terminated" fullword ascii

	condition:
		( uint16(0)==0x7362 and all of them )
}
