rule SIGNATURE_BASE_CN_Honker_Webshell_PHP_Php1 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php1.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "5fe78cc6-8be3-595f-a082-e361259938e5"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L742-L758"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c2f4b150f53c78777928921b3a985ec678bfae32"
		logic_hash = "aadf47ac6231b41e720efdd85c481ebac8fccb572e57b86b27a95dd367c0d81b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s7 = "$sendbuf = \"site exec \".$_POST[\"SUCommand\"].\"\\r\\n\";" fullword ascii
		$s8 = "elseif(function_exists('passthru')){@ob_start();@passthru($cmd);$res = @ob_get_c" ascii
		$s18 = "echo Exec_Run($perlpath.' /tmp/spider_bc '.$_POST['yourip'].' '.$_POST['yourport" ascii

	condition:
		filesize <621KB and all of them
}
