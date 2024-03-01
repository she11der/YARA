rule SIGNATURE_BASE_SUSP_IIS_Config_Virtualdir : FILE
{
	meta:
		description = "Detects suspicious virtual directory configured in IIS pointing to a User folder"
		author = "Florian Roth (Nextron Systems)"
		id = "cfe5ca5e-a0cc-5f60-84d2-1b0538e999c7"
		date = "2021-08-25"
		modified = "2022-09-17"
		reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_proxyshell.yar#L198-L218"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0b9be085957f368bc1890c42e3f1e8b974eed8c77ecb4d2ba6add4d877a9b488"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "<site name=" ascii
		$a2 = "<sectionGroup name=\"system.webServer\">" ascii
		$s2 = " physicalPath=\"C:\\Users\\" ascii
		$fp1 = "Microsoft.Web.Administration" wide
		$fp2 = "<virtualDirectory path=\"/\" physicalPath=\"C:\\Users\\admin\\"

	condition:
		filesize <500KB and all of ($a*) and 1 of ($s*) and not 1 of ($fp*)
}
