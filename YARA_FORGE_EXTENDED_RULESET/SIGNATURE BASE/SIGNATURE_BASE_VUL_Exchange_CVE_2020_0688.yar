rule SIGNATURE_BASE_VUL_Exchange_CVE_2020_0688 : FILE
{
	meta:
		description = "Detects static validation key used by Exchange server in web.config"
		author = "Florian Roth (Nextron Systems)"
		id = "1065f297-0dc4-5dcb-b0f3-c89d06ff5e69"
		date = "2020-02-26"
		modified = "2023-12-05"
		reference = "https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/vul_cve_2020_0688.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "035971028d36c8bbcc6a274817187adfbfefe530ff6808af5a7c0b4667c1bd8b"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$h1 = "<?xml "
		$x1 = "<machineKey validationKey=\"CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF\"" ascii wide

	condition:
		filesize <=300KB and $h1 at 0 and $x1
}
