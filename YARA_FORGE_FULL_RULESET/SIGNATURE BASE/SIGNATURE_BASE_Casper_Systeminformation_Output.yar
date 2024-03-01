rule SIGNATURE_BASE_Casper_Systeminformation_Output
{
	meta:
		description = "Casper French Espionage Malware - System Info Output - http://goo.gl/VRJNLo"
		author = "Florian Roth (Nextron Systems)"
		id = "aaae200c-7ef1-52eb-be5b-36e0ad29ecef"
		date = "2015-03-06"
		modified = "2023-12-05"
		reference = "http://goo.gl/VRJNLo"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_casper.yar#L85-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "83c6216bc3e7fadfe81b9bbaca7b14e3398e972f8298c99a8eb576a40e4b4e1b"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$a0 = "***** SYSTEM INFORMATION ******"
		$a1 = "***** SECURITY INFORMATION ******"
		$a2 = "Antivirus: "
		$a3 = "Firewall: "
		$a4 = "***** EXECUTION CONTEXT ******"
		$a5 = "Identity: "
		$a6 = "<CONFIG TIMESTAMP="

	condition:
		all of them
}
