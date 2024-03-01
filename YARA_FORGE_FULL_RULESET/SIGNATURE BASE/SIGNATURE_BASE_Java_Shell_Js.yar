rule SIGNATURE_BASE_Java_Shell_Js
{
	meta:
		description = "Semi-Auto-generated  - file Java Shell.js.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "eff52c3a-fc3a-5e80-8da9-786168159ebc"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4065-L4077"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "36403bc776eb12e8b7cc0eb47c8aac83"
		logic_hash = "f312298ac30ab57b21222a529b1566b9a66909806e4bc88120ac3992cfd3c6fb"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s2 = "PySystemState.initialize(System.getProperties(), null, argv);" fullword
		$s3 = "public class JythonShell extends JPanel implements Runnable {" fullword
		$s4 = "public static int DEFAULT_SCROLLBACK = 100"

	condition:
		2 of them
}
