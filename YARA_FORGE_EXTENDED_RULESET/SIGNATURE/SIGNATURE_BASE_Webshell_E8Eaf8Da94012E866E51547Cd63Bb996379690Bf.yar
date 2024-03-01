rule SIGNATURE_BASE_Webshell_E8Eaf8Da94012E866E51547Cd63Bb996379690Bf : FILE
{
	meta:
		description = "Detects a web shell"
		author = "Florian Roth (Nextron Systems)"
		id = "8fda9b9f-9a72-5123-91d7-0d0aec9e17bc"
		date = "2016-09-10"
		modified = "2023-12-05"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L9593-L9608"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "044491f0b07ef606aa76e70a07d161565f9cecf73e8f9f8db63cacc1c475b056"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "027544baa10259939780e97dc908bd43f0fb940510119fc4cce0883f3dd88275"

	strings:
		$x1 = "@exec('./bypass/ln -s /etc/passwd 1.php');" fullword ascii
		$x2 = "echo \"<iframe src=mysqldumper/index.php width=100% height=100% frameborder=0></iframe> \";" fullword ascii
		$x3 = "@exec('tar -xvf mysqldumper.tar.gz');" fullword ascii

	condition:
		( uint16(0)==0x213c and filesize <100KB and 1 of ($x*)) or (2 of them )
}
