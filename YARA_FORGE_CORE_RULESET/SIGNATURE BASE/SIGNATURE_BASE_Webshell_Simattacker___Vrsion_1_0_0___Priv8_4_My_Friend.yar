rule SIGNATURE_BASE_Webshell_Simattacker___Vrsion_1_0_0___Priv8_4_My_Friend
{
	meta:
		description = "PHP Webshells Github Archive - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
		author = "Florian Roth (Nextron Systems)"
		id = "3e0bae7d-77a1-5439-bbe7-177bec23cea0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5723-L5740"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "6454cc5ab73143d72cf0025a81bd1fe710351b44"
		logic_hash = "63ebb0c673a5aee05d2d9d571ebf63942d826b5148a5f7ed587ba1efbb0dc923"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "&nbsp;Iranian Hackers : WWW.SIMORGH-EV.COM <br>" fullword
		$s5 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
		$s10 = "<a style=\"TEXT-DECORATION: none\" href=\"http://www.simorgh-ev.com\">" fullword
		$s16 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
		$s17 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
		$s19 = "$Comments=$_POST['Comments'];" fullword
		$s20 = "Victim Mail :<br><input type='text' name='to' ><br>" fullword

	condition:
		3 of them
}
