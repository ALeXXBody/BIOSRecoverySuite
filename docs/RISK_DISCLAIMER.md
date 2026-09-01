# RISK DISCLAIMER

**BIOS Recovery Suite modifies firmware images. Improper use can permanently brick your device (make it unbootable).**

## Understanding the Risks

1. **BIOS Modification is Dangerous** - A corrupted BIOS can prevent your computer from booting. Always:
   - Create a full backup of your original BIOS before making any changes
   - Verify you can flash back to your original BIOS using an SPI programmer if needed

2. **Intel ME Cleaning** - Modifying the ME region involves:
   - Removing signed firmware partitions
   - Setting HAP/AltMeDisable bits
   - This may be prevented by Intel Boot Guard on some systems

3. **Password Removal** - Removing passwords may:
   - Trigger anti-theft mechanisms
   - Invalidate warranties
   - Be illegal if used on systems you don't own

4. **DMI Modification** - Changing serial numbers, UUIDs, or other identifiers may:
   - Be illegal in some jurisdictions
   - Invalidate software licenses
   - Trigger anti-tamper mechanisms

## Legal Considerations

Only use this tool on systems:
- You own
- You have authorization to modify
- For legitimate repair purposes

## Testing

Always test modified images on a system with:
- Dual-BIOS recovery
- External SPI programmer
- Known-good backup

## Liability

The developers provide this software as-is with no warranty. Users assume all responsibility for:
- Any damage to hardware
- Any legal consequences
- Any data loss

## Best Practices

1. **Always** use an external SPI programmer (CH341A, etc.) for flashing
2. **Always** verify your ROM dump is valid before modifying
3. **Always** keep multiple backups in different locations
4. **Never** flash a modified image without a recovery path
5. **Document** all changes you make
