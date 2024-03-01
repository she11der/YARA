rule SIGNATURE_BASE_VUL_Tomcat_Catalina_CVE_2020_1938 : FILE
{
	meta:
		description = "Detects a possibly active and vulnerable Tomcat configuration that includes an accessible and unprotected AJP connector (you can ignore backup files or files that are not actively used)"
		author = "Florian Roth (Nextron Systems)"
		id = "d23af7ce-eb5d-50aa-be02-b4bf858641c2"
		date = "2020-02-28"
		modified = "2023-12-05"
		reference = "https://www.chaitin.cn/en/ghostcat"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/vul_cve_2020_1938.yar#L2-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "902b469c8a31add2254e8d5ade6bc22f1bc0a2b10ea70f3131f0640f2900e667"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$h1 = "<?xml "
		$a1 = "<Service name=\"Catalina\">" ascii
		$v1 = "<Connector port=\"8009\" protocol=\"AJP/1.3\" redirectPort=\"8443\"/>" ascii
		$fp1 = "<!--<Connector port=\"8009\" protocol=\"AJP/1.3\" redirectPort=\"8443\"" ascii
		$fp2 = " secret=\"" ascii
		$fp3 = " requiredSecret=\"" ascii

	condition:
		$h1 at 0 and filesize <=300KB and $a1 and $v1 and not 1 of ($fp*)
}
