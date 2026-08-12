using Aegis.Core.Policy;
using Xunit;

namespace Aegis.Tests;

public class DefensePolicyTests
{
    [Fact]
    public void NotificationSettings_InteractiveNotificationsEnabled_IsTwoWayViewOfMode()
    {
        var settings = new NotificationSettings();
        Assert.Equal(NotificationMode.AlertsOnly, settings.Mode);
        Assert.False(settings.InteractiveNotificationsEnabled);

        settings.InteractiveNotificationsEnabled = true;
        Assert.Equal(NotificationMode.InteractiveAction, settings.Mode);

        settings.InteractiveNotificationsEnabled = false;
        Assert.Equal(NotificationMode.AlertsOnly, settings.Mode);

        settings.Mode = NotificationMode.InteractiveAction;
        Assert.True(settings.InteractiveNotificationsEnabled);
    }

    [Fact]
    public void EngineToggles_AutoRemediationEnabled_DefaultsOff()
    {
        // Opt-in only, same as AutoContainmentEnabled - a fresh default policy must never
        // auto-remediate until an operator consciously enables it.
        var toggles = new EngineToggles();
        Assert.False(toggles.AutoRemediationEnabled);
        Assert.False(toggles.AutoContainmentEnabled);
    }

    [Fact]
    public void DefensePolicy_CreateDefault_NotificationsDefaultToAlertsOnly()
    {
        var policy = DefensePolicy.CreateDefault("issuer-1");
        Assert.Equal(NotificationMode.AlertsOnly, policy.Notifications.Mode);
        Assert.True(policy.Notifications.NotifyOnResponseActions);
        Assert.False(policy.Engines.AutoRemediationEnabled);
    }
}
