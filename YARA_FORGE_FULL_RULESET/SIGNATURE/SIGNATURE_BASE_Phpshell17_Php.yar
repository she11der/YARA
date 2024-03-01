rule SIGNATURE_BASE_Phpshell17_Php
{
	meta:
		description = "Semi-Auto-generated  - file phpshell17.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "ea1f657c-2023-50bb-a2ee-33c53ee8fb5e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4225-L4237"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9a928d741d12ea08a624ee9ed5a8c39d"
		logic_hash = "a9306747a5c9756f393c61562ed4a601c75c3a9491ad19a7b7dbae1fbd505e9a"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" fullword
		$s1 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]<?php echo PHPSHELL_VERSION ?></"
		$s2 = "href=\"mailto: [YOU CAN ENTER YOUR MAIL HERE]- [ADDITIONAL TEXT]</a></i>" fullword

	condition:
		1 of them
}
