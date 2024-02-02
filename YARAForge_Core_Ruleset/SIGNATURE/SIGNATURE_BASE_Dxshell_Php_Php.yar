rule SIGNATURE_BASE_Dxshell_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file DxShell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "b89930b7-acf3-5078-8429-d59e27e4b00c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4381-L4392"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "33a2b31810178f4c2e71fbdeb4899244"
		logic_hash = "821f9295eba6119ad08349e769d1909cd7836b4e35795915e94095cf715dc6e5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
		$s2 = "print \"\\n\".'<tr><td width=100pt class=linelisting><nobr>POST (php eval)</td><"

	condition:
		1 of them
}