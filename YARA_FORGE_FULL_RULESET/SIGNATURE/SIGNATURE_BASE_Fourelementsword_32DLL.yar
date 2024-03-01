rule SIGNATURE_BASE_Fourelementsword_32DLL : FILE
{
	meta:
		description = "Detects FourElementSword Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "fc801364-9f40-50eb-90e1-99f8605014c7"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_four_element_sword.yar#L51-L68"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7a200c4df99887991c638fe625d07a4a3fc2bdc887112437752b3df5c8da79b6"
		logic_hash = "b44870975f126b8603db04b97b748f7a5a75675ffe57037f613c11d6048200b1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "%temp%\\tmp092.tmp" fullword ascii
		$s1 = "\\System32\\ctfmon.exe" ascii
		$s2 = "%SystemRoot%\\System32\\" ascii
		$s3 = "32.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <660KB and $x1) or ( all of them )
}
