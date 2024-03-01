rule SIGNATURE_BASE_CVE_2017_8759_SOAP_Excel : CVE_2017_8759 FILE
{
	meta:
		description = "Detects malicious files related to CVE-2017-8759"
		author = "Florian Roth (Nextron Systems)"
		id = "940ec910-49a4-5271-97e4-8536db271b80"
		date = "2017-09-15"
		modified = "2023-12-05"
		reference = "https://twitter.com/buffaloverflow/status/908455053345869825"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/exploit_cve_2017_8759.yar#L63-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "adea595b251796e93cdc54cc59198d88a68e28d42899c90721f63f6813df24fe"
		score = 60
		quality = 83
		tags = "CVE-2017-8759, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "|'soap:wsdl=" ascii wide nocase

	condition:
		( filesize <300KB and 1 of them )
}
