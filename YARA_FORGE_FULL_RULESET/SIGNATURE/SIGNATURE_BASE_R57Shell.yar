rule SIGNATURE_BASE_R57Shell
{
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "1f1070e8-e82c-5cae-a64a-cd5028adae97"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7714-L7725"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8023394542cddf8aee5dec6072ed02b5"
		logic_hash = "40ff6bceb3f9bd95fbf5e75681fadadaa64243007e10fcc86bb909282b8161c5"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to"

	condition:
		all of them
}
