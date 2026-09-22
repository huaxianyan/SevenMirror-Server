package adminweb

import (
	"net/http"
	"strings"
	"time"
)

const (
	timezoneCookieName = "sevenmirror_admin_timezone"
	// The choice describes this browser, not this sign-in, so it outlives the
	// in-memory session on purpose: signing out and back in must not reset it.
	timezoneCookieLifetime = 365 * 24 * time.Hour
	utcZoneName            = "UTC"
)

// consoleTimezones is the offered list. It is curated rather than exhaustive:
// between it the whole range of real offsets is reachable, and the names are the
// ones an administrator recognizes. A name that is not offered still works when
// it is already in the cookie, so a hand-edited or previously stored value never
// breaks the page.
var consoleTimezones = []timezoneGroup{
	{Label: "常用", Zones: []string{
		"UTC", "Asia/Shanghai", "Asia/Hong_Kong", "Asia/Taipei",
		"Asia/Tokyo", "Asia/Seoul", "Asia/Singapore",
	}},
	{Label: "亚洲与中东", Zones: []string{
		"Asia/Kolkata", "Asia/Kathmandu", "Asia/Dhaka", "Asia/Bangkok",
		"Asia/Ho_Chi_Minh", "Asia/Kuala_Lumpur", "Asia/Manila", "Asia/Jakarta",
		"Asia/Dubai", "Asia/Riyadh", "Asia/Tehran", "Asia/Istanbul",
	}},
	{Label: "欧洲", Zones: []string{
		"Europe/London", "Europe/Dublin", "Europe/Lisbon", "Europe/Paris",
		"Europe/Berlin", "Europe/Amsterdam", "Europe/Madrid", "Europe/Rome",
		"Europe/Zurich", "Europe/Warsaw", "Europe/Stockholm", "Europe/Athens",
		"Europe/Helsinki", "Europe/Kyiv", "Europe/Moscow",
	}},
	{Label: "美洲", Zones: []string{
		"America/St_Johns", "America/Halifax", "America/New_York", "America/Chicago",
		"America/Denver", "America/Phoenix", "America/Los_Angeles", "America/Anchorage",
		"America/Mexico_City", "America/Bogota", "America/Lima", "America/Santiago",
		"America/Sao_Paulo", "America/Buenos_Aires",
	}},
	{Label: "大洋洲与非洲", Zones: []string{
		"Australia/Perth", "Australia/Adelaide", "Australia/Brisbane",
		"Australia/Sydney", "Australia/Melbourne", "Pacific/Auckland",
		"Pacific/Honolulu", "Africa/Cairo", "Africa/Johannesburg",
		"Africa/Lagos", "Africa/Nairobi",
	}},
}

type timezoneGroup struct {
	Label string
	Zones []string
}

type timezoneGroupView struct {
	Label   string
	Options []timezoneOptionView
}

type timezoneOptionView struct {
	Name     string
	Label    string
	Selected bool
}

// timezoneView is what the settings panel renders: the zone in effect here, and
// the offered alternatives.
type timezoneView struct {
	Name   string
	Label  string
	Groups []timezoneGroupView
}

// timezoneName answers with the zone this browser asked for. An absent cookie, an
// empty value or a name that is not a zone all fall back to UTC, which is what the
// page showed before the setting existed. The value only ever reaches formatting,
// so a bad one is not an error worth reporting to the administrator.
func (h *Handler) timezoneName(r *http.Request) string {
	cookie, err := r.Cookie(timezoneCookieName)
	if err != nil {
		return utcZoneName
	}
	name := strings.TrimSpace(cookie.Value)
	if _, err := time.LoadLocation(name); err != nil {
		return utcZoneName
	}
	return name
}

func (h *Handler) displayLocation(r *http.Request) *time.Location {
	if location, err := time.LoadLocation(h.timezoneName(r)); err == nil {
		return location
	}
	return time.UTC
}

// timezoneDisplay builds the picker. Labels carry the offset the zone is on right
// now, so choosing one does not require knowing offsets by heart.
func timezoneDisplay(moment time.Time, current string) timezoneView {
	view := timezoneView{Name: current, Label: timezoneLabel(current, moment)}
	for _, group := range consoleTimezones {
		optionGroup := timezoneGroupView{Label: group.Label}
		for _, name := range group.Zones {
			optionGroup.Options = append(optionGroup.Options, timezoneOptionView{
				Name: name, Label: timezoneLabel(name, moment), Selected: name == current,
			})
		}
		view.Groups = append(view.Groups, optionGroup)
	}
	return view
}

func timezoneLabel(name string, moment time.Time) string {
	location, err := time.LoadLocation(name)
	if err != nil || name == utcZoneName {
		return name
	}
	return name + "（UTC" + moment.In(location).Format("-07:00") + "）"
}

// changeTimezone records the browser's display time zone. It is a view
// preference and nothing else: the registry, the device APIs and every stored
// timestamp stay on UTC, and this cookie is the only place the choice lives.
func (h *Handler) changeTimezone(w http.ResponseWriter, r *http.Request) {
	_, digest, ok := h.authorizeManagementPost(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("timezone"))
	if _, err := time.LoadLocation(name); err != nil {
		h.finishAction(w, r, digest, sectionSettings, &flashMessage{
			Kind: "error", Message: "没有这个时区。请从列表里重新选择一个。",
		})
		return
	}
	h.setTimezoneCookie(w, name)
	h.finishAction(w, r, digest, sectionSettings, &flashMessage{
		Kind: "success", Message: "时间显示已改为 " + timezoneLabel(name, h.now()) + "。",
	})
}

func (h *Handler) setTimezoneCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: timezoneCookieName, Value: name, Path: "/",
		MaxAge:   int(timezoneCookieLifetime.Seconds()),
		HttpOnly: true, Secure: h.secureCookies, SameSite: http.SameSiteStrictMode,
	})
}
