rule SIGNATURE_BASE_Webshell_2008_2009Mssql_Phpspy_2005_Full_Phpspy_2006_Arabicspy_Hkrkoz
{
	meta:
		description = "Web Shell"
		author = "Florian Roth (Nextron Systems)"
		id = "41a0560a-b22e-5028-8ad1-710c5758cb1d"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L2837-L2859"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2d78db4d45a35d6a78d4288e00a382a0937e3806f0570bd353b88955664a47f6"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
		hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash3 = "40a1f840111996ff7200d18968e42cfe"
		hash4 = "e0202adff532b28ef1ba206cf95962f2"
		hash5 = "802f5cae46d394b297482fd0c27cb2fc"

	strings:
		$s0 = "$this -> addFile($content, $filename);" fullword
		$s3 = "function addFile($data, $name, $time = 0) {" fullword
		$s8 = "function unix2DosTime($unixtime = 0) {" fullword
		$s9 = "foreach($filelist as $filename){" fullword

	condition:
		all of them
}
