rule SIGNATURE_BASE_Groups_Cpassword : FILE
{
	meta:
		description = "Groups XML contains cpassword value, which is decrypted password - key is in MSDN http://goo.gl/mHrC8P"
		author = "Florian Roth (Nextron Systems)"
		id = "37036df9-871f-5ecd-acac-6a064d298115"
		date = "2015-09-08"
		modified = "2023-12-05"
		reference = "http://www.grouppolicy.biz/2013/11/why-passwords-in-group-policy-preference-are-very-bad/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_gpp_cpassword.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "de37dc77d9a2462f5d54ad5225405c6d95dad39e67a893f5442b26dc641a20f9"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = / cpassword=\"[^\"]/ ascii
		$s2 = " changeLogon=" ascii
		$s3 = " description=" ascii
		$s4 = " acctDisabled=" ascii

	condition:
		uint32be(0)==0x3C3F786D and filesize <1000KB and all of ($s*)
}
