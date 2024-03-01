rule SIGNATURE_BASE_CVE_2017_8759_SOAP_Via_JS : FILE
{
	meta:
		description = "Detects SOAP WDSL Download via JavaScript"
		author = "Florian Roth (Nextron Systems)"
		id = "9e96cea3-4282-5f25-ad37-51bd69258790"
		date = "2017-09-14"
		modified = "2023-12-05"
		reference = "https://twitter.com/buffaloverflow/status/907728364278087680"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/exploit_cve_2017_8759.yar#L47-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3c170479283fe859b9ecfba4834396aaf78b375472250a4b188bc913f69c97fd"
		score = 60
		quality = 81
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "GetObject(\"soap:wsdl=https://" ascii wide nocase
		$s2 = "GetObject(\"soap:wsdl=http://" ascii wide nocase

	condition:
		( filesize <3KB and 1 of them )
}
