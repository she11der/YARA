rule SIGNATURE_BASE_CN_Tools_Old : FILE
{
	meta:
		description = "Chinese Hacktool Set - file old.php"
		author = "Florian Roth (Nextron Systems)"
		id = "bfdb84e8-e5a8-53a4-ae71-e0d1b38d38ef"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L239-L255"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f8a007758fda8aa1c0af3c43f3d7e3186a9ff307"
		logic_hash = "3f0ac357e9a9fb4ee937b53145b33ba1041310d979cbc3feb0a4caf026b9b730"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
		$s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
		$s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
		$s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii

	condition:
		filesize <6KB and all of them
}
