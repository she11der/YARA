rule SIGNATURE_BASE_Webshell_Hiddens_Shell_V1
{
	meta:
		description = "PHP Webshells Github Archive - file hiddens shell v1.php"
		author = "Florian Roth (Nextron Systems)"
		id = "7194998e-c84c-5f59-92fe-857ecf7e8e88"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L5948-L5959"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "1674bd40eb98b48427c547bf9143aa7fbe2f4a59"
		logic_hash = "b76400c320e6294b0c831fbbb8e08a9d2097fbb027065f9c4b496d4b005ba016"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U"

	condition:
		all of them
}
