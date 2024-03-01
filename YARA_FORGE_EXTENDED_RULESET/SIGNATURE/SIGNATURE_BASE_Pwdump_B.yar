import "pe"

rule SIGNATURE_BASE_Pwdump_B : FILE
{
	meta:
		description = "Detects a tool used by APT groups - file PwDump.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "aad974f1-76bf-5aae-8376-a4fd3f27b345"
		date = "2016-09-08"
		modified = "2023-12-05"
		reference = "http://goo.gl/igxLyF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3386-L3406"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d50ad359b9433439cddda9408d227f35ee8de3280ad24f42c5e6ef1e6a1526bd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3c796092f42a948018c3954f837b4047899105845019fce75a6e82bc99317982"

	strings:
		$x1 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineName" fullword ascii
		$x2 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword ascii
		$x3 = "where -x targets a 64-bit host" fullword ascii
		$x4 = "Couldn't delete target executable from remote machine: %d" fullword ascii
		$s1 = "lsremora64.dll" fullword ascii
		$s2 = "lsremora.dll" fullword ascii
		$s3 = "servpw.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 1 of ($x*)) or (3 of them )
}
