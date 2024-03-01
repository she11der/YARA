rule SIGNATURE_BASE_Oracle_Data
{
	meta:
		description = "Chinese Hacktool Set - file oracle_data.php"
		author = "Florian Roth (Nextron Systems)"
		id = "faa62dcc-0f59-573c-8722-d07216de151f"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L123-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6cf070017be117eace4752650ba6cf96d67d2106"
		logic_hash = "1ab9b6c4349dd891103a24a77c93c2abb784d3ed616523f3aaec68b05082983e"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
		$s1 = "if(isset($_REQUEST['id']))" fullword ascii
		$s2 = "$id=$_REQUEST['id'];" fullword ascii

	condition:
		all of them
}
