rule SIGNATURE_BASE_CN_Tools_Item : FILE
{
	meta:
		description = "Chinese Hacktool Set - file item.php"
		author = "Florian Roth (Nextron Systems)"
		id = "954f24c9-d7d5-56d3-86f0-0cf8832640dd"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L275-L291"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a584db17ad93f88e56fd14090fae388558be08e4"
		logic_hash = "1e927fd093aa11ad525f3f64d657f314520669b4237eac8f87d0be53cd848044"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
		$s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
		$s3 = "$sWget=\"index.asp\";" fullword ascii
		$s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii

	condition:
		filesize <4KB and all of them
}
