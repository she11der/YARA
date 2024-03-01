rule MALPEDIA_Win_Dtrack_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a233c383-e1c0-5a80-b962-04f71174b55f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dtrack"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.dtrack_auto.yar#L1-L160"
		license_url = "N/A"
		logic_hash = "da8244413760aff3fc60e26778e79f2591abffda2d0aa55a6f2fe1a5cc4b0aa3"
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
		$sequence_0 = { 52 8b4508 50 e8???????? 83c414 8b4d10 51 }
		$sequence_1 = { ff15???????? 8d85dcfdffff 50 6a01 }
		$sequence_2 = { 8955f0 8b45f0 0fb68899010000 51 8b55f0 }
		$sequence_3 = { 8d85ecfeffff 50 8d8dc8fdffff 51 8d95ccfdffff }
		$sequence_4 = { 0345f4 8810 ebac e9???????? 8be5 }
		$sequence_5 = { 52 8d8590f5ffff 50 ff15???????? c685a0f8ffff00 6803010000 6a00 }
		$sequence_6 = { c685b8fbffff00 6803010000 6a00 8d8db9fbffff 51 e8???????? }
		$sequence_7 = { 51 e8???????? 83c410 8b558c 52 }
		$sequence_8 = { 8b8520f5ffff 8a4801 888d1ff5ffff 838520f5ffff01 }
		$sequence_9 = { d1e9 894df8 8b5518 8955fc c745f000000000 eb09 }
		$sequence_10 = { 8b45fc c1e808 8b4dfc c1e910 }
		$sequence_11 = { c1e810 23c8 33d1 8855f7 8b4df8 c1e908 8b55fc }
		$sequence_12 = { 894d14 8b45f8 c1e018 8b4dfc }
		$sequence_13 = { 6867452301 8b4d10 51 8b55f4 52 }
		$sequence_14 = { eb64 8b4d10 51 6a00 8b55f4 52 e8???????? }

	condition:
		7 of them and filesize <1736704
}