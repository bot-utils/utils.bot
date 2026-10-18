window.addEventListener("DOMContentLoaded", function () {
  SwaggerUIBundle({
    url: "/openapi",
    dom_id: "#swagger-ui",
    deepLinking: true,
    docExpansion: "none",
    queryConfigEnabled: false,
    validatorUrl: null,
    persistAuthorization: false,
    withCredentials: false,
    supportedSubmitMethods: ["get", "post"],
    presets: [SwaggerUIBundle.presets.apis],
    layout: "BaseLayout"
  });
});
