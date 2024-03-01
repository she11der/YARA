import "pe"

rule SIGNATURE_BASE_APT_Hacktool_PS1_COSMICGALE_1
{
	meta:
		description = "This rule detects various unique strings related to COSMICGALE. COSMICGALE is a credential theft and reconnaissance PowerShell script that collects credentials using the publicly available Get-PassHashes routine. COSMICGALE clears log files, writes acquired data to a hard coded path, and encrypts the file with a password."
		author = "FireEye"
		id = "c094943c-288e-5835-8066-8e95a992c76c"
		date = "2020-12-14"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_solarwinds_sunburst.yar#L119-L140"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c7b4d3c29d57b8db8d21e3a436c83617bc3fe14e66ccc1500b33a3774f09ee12"
		score = 85
		quality = 65
		tags = ""

	strings:
		$sr1 = /\[byte\[\]\]@\([\x09\x20]{0,32}0xaa[\x09\x20]{0,32},[\x09\x20]{0,32}0xd3[\x09\x20]{0,32},[\x09\x20]{0,32}0xb4[\x09\x20]{0,32},[\x09\x20]{0,32}0x35[\x09\x20]{0,32},/ ascii nocase wide
		$sr2 = /\[bitconverter\]::toint32\(\$\w{1,64}\[0x0c..0x0f\][\x09\x20]{0,32},[\x09\x20]{0,32}0\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}0xcc\x3b/ ascii nocase wide
		$sr3 = /\[byte\[\]\]\(\$\w{1,64}\.padright\(\d{1,2}\)\.substring\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,2}\)\.tochararray\(\)\)/ ascii nocase wide
		$ss1 = "[text.encoding]::ascii.getbytes(\"ntpassword\x600\");" ascii nocase wide
		$ss2 = "system\\currentcontrolset\\control\\lsa\\$_" ascii nocase wide
		$ss3 = "[security.cryptography.md5]::create()" ascii nocase wide
		$ss4 = "[system.security.principal.windowsidentity]::getcurrent().name" ascii nocase wide
		$ss5 = "out-file" ascii nocase wide
		$ss6 = "convertto-securestring" ascii nocase wide

	condition:
		all of them
}
