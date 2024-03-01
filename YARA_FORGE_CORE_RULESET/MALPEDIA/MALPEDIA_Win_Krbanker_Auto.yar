rule MALPEDIA_Win_Krbanker_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "236e4eb3-f9a9-5a5c-939d-2dd344c94ac6"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.krbanker"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.krbanker_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "d1369d0e33548d319048c3c036e2e47c22a922a80b7ada061139a11ddd9f8b91"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 83c404 58 8945dc 837ddc00 }
		$sequence_1 = { 83c404 58 8945fc b8???????? 50 }
		$sequence_2 = { 6801000000 bb40010000 e8???????? 83c410 8945c8 6801010080 6a00 }
		$sequence_3 = { 0faf03 ebf5 8bc8 c3 55 8bec 83c4f4 }
		$sequence_4 = { 75a4 dd442410 e8???????? 8ad8 }
		$sequence_5 = { 7762 7415 3d04000080 7417 3d01010080 }
		$sequence_6 = { bb40010000 e8???????? 83c410 8945cc ff75cc ff75d0 }
		$sequence_7 = { 8a5c2410 8ac3 5e 5b c3 8b542410 83ec0c }
		$sequence_8 = { 8b5dfc 83c304 895df8 8965f4 ff7514 }
		$sequence_9 = { 03d8 895dd4 8b5df8 e8???????? }

	condition:
		7 of them and filesize <1826816
}
