# tc-vmc-frontend
VM websocket communication layer for the frontend

# TODO

The Javascript distribution was generated for the browser as
a UMD module, i.e. everything is available under a global
variable named `vmc`. The types do not indicate this because
we are currently hacking Typescript big time in tiCrypt, and
once we fix the tiCrypt type system, this library and all the
others will be switched to pure Typescript modules.