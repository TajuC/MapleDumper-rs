const FUNCTIONS: &[&str] = &[
    "Enter_CS",
    "Exit_CS",
    "GetLevel",
    "GetPlayerXY",
    "GetSkillLevel",
    "GetSkillObject",
    "SkillInject",
    "KeyPress",
    "TeleportP",
    "TeleportE",
    "TeleportF",
    "ChangeChannel",
    "gm4",
    "gm3",
    "gm2",
    "gm1",
    "nodelay",
    "UnlimitedAttack",
    "Cooldown",
    "Flashjump",
    "GetRectMob",
    "FMA",
];

const GLOBALS: &[&str] = &[
    "CUserLocal",
    "CWvsContext",
    "CPlaceBase",
    "CWallBase",
    "CPlayerCount",
    "CMapBase",
    "CClickBase",
    "GameTimeBase",
    "MobPool",
    "ItemHover",
    "LastSkill",
    "CSkillBase",
    "CRuneBase",
    "MSCRC",
    "MSCRCExit",
];

const OFFSETS: &[&str] = &[
    "Channel",
    "Server",
    "InTown",
    "InCashShop",
    "LoginState",
    "HWND",
    "FieldId",
    "RedDotCount",
    "RuneBuff",
    "Navigation",
    "CharName",
    "WeaponID",
    "WallStruct",
    "Wall_Left",
    "Wall_Top",
    "Wall_Right",
    "Wall_Bottom",
    "GameTime",
    "MaxHpPtr",
    "MaxHpKey",
    "MaxHpEnc",
    "CurHpPtr",
    "CurHpKey",
    "CurHpEnc",
    "List",
    "Template",
    "MobID",
    "Invincible",
    "SecuredPos",
    "Sec_X_Ptr",
    "Sec_Y_Ptr",
    "ZRefPtr",
];

const PACKETS: &[&str] = &[
    "ProcessPacket",
    "Decode1",
    "Decode2",
    "Decode4",
    "Decode8",
    "DecodeStr",
    "DecodeBuffer",
    "SendPacket",
    "COutPacket",
    "Encode1",
    "Encode2",
    "Encode4",
    "Encode8",
    "EncodeStr",
    "EncodeBuffer",
    "SendPacket_EH",
    "SendPacket_EH_CClientSocket",
];

const ITEMS: &[&str] = &["HoveredItemPath"];

pub const UNCATEGORIZED: &str = "uncategorized";

const TABLE: &[(&str, &[&str])] = &[
    ("functions", FUNCTIONS),
    ("globals", GLOBALS),
    ("offsets", OFFSETS),
    ("packets", PACKETS),
    ("items", ITEMS),
];

#[must_use]
pub fn builtin_category(name: &str) -> &'static str {
    TABLE
        .iter()
        .find(|(_, names)| names.contains(&name))
        .map_or(UNCATEGORIZED, |&(category, _)| category)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_names_map_to_their_groups() {
        assert_eq!(builtin_category("CUserLocal"), "globals");
        assert_eq!(builtin_category("EncodeStr"), "packets");
        assert_eq!(builtin_category("GetLevel"), "functions");
        assert_eq!(builtin_category("CurHpPtr"), "offsets");
        assert_eq!(builtin_category("HoveredItemPath"), "items");
    }

    #[test]
    fn unknown_names_are_flagged_not_hidden_in_globals() {
        assert_eq!(builtin_category("SomethingNew"), UNCATEGORIZED);
        assert_ne!(builtin_category("SomethingNew"), "globals");
    }
}
