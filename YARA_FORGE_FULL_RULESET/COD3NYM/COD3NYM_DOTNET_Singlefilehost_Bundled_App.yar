import "pe"

rule COD3NYM_DOTNET_Singlefilehost_Bundled_App : FILE
{
	meta:
		description = "Detects single file host .NET bundled apps."
		author = "Jonathan Peters"
		id = "061bd294-58d6-57be-b8b5-b8a8f31ce316"
		date = "2024-01-02"
		modified = "2024-01-05"
		reference = "https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/yara/dotnet/framework_identiciation.yar#L3-L17"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		logic_hash = "12075b07a9feb951898ac8eba303471d9253ed9535db927244e5562f4fad33d6"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$ = "singlefilehost.exe" ascii
		$ = "singlefilehost.pdb" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them and pe.exports("DotNetRuntimeInfo") and pe.exports("CLRJitAttachState")
}
