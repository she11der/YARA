rule SIGNATURE_BASE_Webshell_Lamashell
{
	meta:
		description = "PHP Webshells Github Archive - file lamashell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "60e39eed-baa2-5999-8560-0a0242ce2608"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6122-L6138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b71181e0d899b2b07bc55aebb27da6706ea1b560"
		logic_hash = "e58dbd6b9c65a139828890a3fadfad9031580fe189066489d266d37d7078ad98"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "if(($_POST['exe']) == \"Execute\") {" fullword
		$s8 = "$curcmd = $_POST['king'];" fullword
		$s16 = "\"http://www.w3.org/TR/html4/loose.dtd\">" fullword
		$s18 = "<title>lama's'hell v. 3.0</title>" fullword
		$s19 = "_|_  O    _    O  _|_"
		$s20 = "$curcmd = \"ls -lah\";" fullword

	condition:
		2 of them
}
