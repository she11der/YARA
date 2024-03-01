rule SIGNATURE_BASE_Webshell_Webshells_New_Php2
{
	meta:
		description = "Web shells - generated from file php2.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3268-L3281"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "fbf2e76e6f897f6f42b896c855069276"
		logic_hash = "0350df076a25af77fbd8d5db2b38438a10cd5b9237b23b2f64c6360607b41982"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<?php $s=@$_GET[2];if(md5($s.$s)=="

	condition:
		all of them
}
