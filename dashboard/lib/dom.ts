// Firefox restores a button's previous enabled/disabled state when a page is reloaded
// (form-state restoration). If the server rendered the button disabled while data was
// loading, React then sees a different attribute and reports a hydration mismatch.
// autocomplete="off" opts the element out of that restoration. React passes the attribute
// through; it is only missing from the TypeScript types for <button>, hence the cast.
export const noFormRestore = { autoComplete: "off" } as object;
