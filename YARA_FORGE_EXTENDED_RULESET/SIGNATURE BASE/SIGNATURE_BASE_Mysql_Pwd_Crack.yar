rule SIGNATURE_BASE_Mysql_Pwd_Crack : FILE
{
	meta:
		description = "Chinese Hacktool Set - file mysql_pwd_crack.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3ddeb1c7-e124-5e9e-abcf-3856e0561165"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1913-L1930"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "57d1cb4d404688804a8c3755b464a6e6248d1c73"
		logic_hash = "d272b98a6cf2749482ee501734d0043564ba528770161cb0ed4f032409305f22"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "mysql_pwd_crack 127.0.0.1 -x 3306 -p root -d userdict.txt" fullword ascii
		$s2 = "Successfully --> username %s password %s " fullword ascii
		$s3 = "zhouzhen@gmail.com http://zhouzhen.eviloctal.org" fullword ascii
		$s4 = "-a automode  automatic crack the mysql password " fullword ascii
		$s5 = "mysql_pwd_crack 127.0.0.1 -x 3306 -a" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 1 of them
}
