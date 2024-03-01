rule SIGNATURE_BASE_Webshell_Ghost_Source_Icesword_Silic
{
	meta:
		description = "Web Shell - from files ghost_source.php, icesword.php, silic.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L2110-L2127"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "22879d5279866e3c25a5b41a98b44595f191cfcac6489208b0bdb6b7ca7201e5"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "cbf64a56306c1b5d98898468fc1fdbd8"
		hash1 = "6e20b41c040efb453d57780025a292ae"
		hash2 = "437d30c94f8eef92dc2f064de4998695"

	strings:
		$s3 = "if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $"
		$s6 = "if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST["

	condition:
		all of them
}
