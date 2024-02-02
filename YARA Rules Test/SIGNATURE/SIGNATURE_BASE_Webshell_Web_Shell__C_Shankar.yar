rule SIGNATURE_BASE_Webshell_Web_Shell__C_Shankar
{
	meta:
		description = "PHP Webshells Github Archive - file Web-shell (c)ShAnKaR.php"
		author = "Florian Roth (Nextron Systems)"
		id = "966f5580-21c5-5ecf-b500-bde3d1ba4494"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L6388-L6402"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "3dd4f25bd132beb59d2ae0c813373c9ea20e1b7a"
		logic_hash = "9d320eed18a5d76a87cee4ea0fa9caf08f096f7eeaab55420540aa082b596e0f"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "header(\"Content-Length: \".filesize($_POST['downf']));" fullword
		$s5 = "if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump"
		$s6 = "write(\"#\\n#Server : \".getenv('SERVER_NAME').\"" fullword
		$s12 = "foreach(@file($_POST['passwd']) as $fed)echo $fed;" fullword

	condition:
		2 of them
}