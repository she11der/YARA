rule MALPEDIA_Win_Classfon_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "68a5b428-fba0-5238-83c9-3255bfbb3ff5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.classfon"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.classfon_auto.yar#L1-L122"
		license_url = "N/A"
		logic_hash = "752d9b4933679b22e7a2ada3974321921c7722355427af1c70ee3b8ff2e5df5f"
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
		$sequence_0 = { 85c0 7462 8b542408 8b8e00020000 8b44240c }
		$sequence_1 = { 8b742418 83f8ff 898600020000 7508 5f 33c0 }
		$sequence_2 = { 50 ffd3 89be04020000 8b8600020000 3bc7 740e }
		$sequence_3 = { 8b1d???????? a1???????? 50 57 ff15???????? }
		$sequence_4 = { 8d4c241c 8d542424 51 8b4c2414 8d442424 52 }
		$sequence_5 = { 8d842430020000 50 ffd7 8d8c2430010000 51 ffd7 8b542424 }
		$sequence_6 = { 6a00 6a00 6a00 6802000004 6a00 899610020000 }
		$sequence_7 = { 68???????? 51 c744242802000000 c744242c2c010000 ff15???????? }
		$sequence_8 = { 50 ff15???????? 8bd8 83fbff 0f849c000000 8b470c 8b5708 }
		$sequence_9 = { 0f85c3000000 8b460c 85c0 0f84c0000000 03c5 }

	condition:
		7 of them and filesize <73728
}