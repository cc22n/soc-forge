
# Integración de IPGeolocation API en plan gratis

Este archivo describe cómo configurar y usar la API de IPGeolocation en su plan gratuito para un agente o aplicación. El plan gratis de IPGeolocation es “forever free”, no requiere tarjeta y entrega 1000 créditos por día de por vida.[page:1]

## Objetivo

Usar la API unificada de IPGeolocation para obtener geolocalización básica por IP con los campos permitidos en el plan gratuito, evitando funciones exclusivas de pago como lookup por dominio, hostname, company, network extendido, seguridad, abuse, bulk lookup y geolocalización en múltiples idiomas.[page:1]

## Qué incluye el plan gratis

El plan gratuito incluye geolocalización esencial por IP, country metadata, currency, datos básicos de ASN y datos de zona horaria acoplados a la respuesta principal.[page:1]

Campos de ejemplo disponibles en free:
- `ip`
- `location` con continente, país, estado, ciudad, código postal, latitud y longitud.[page:2]
- `country_metadata` con `calling_code`, `tld` y `languages`.[page:2]
- `currency` con `code`, `name` y `symbol`.[page:2]
- `asn` con `as_number`, `organization` y `country` en el ejemplo de free plan.[page:1]
- `time_zone` con nombre, offset, hora actual y datos DST.[page:1][page:2]

## Qué no usar en free

No se debe depender en el plan gratis de estas capacidades porque aparecen como no disponibles en Free y reservadas para planes de pago: `Location By Domain`, `Hostname Info`, `Company`, `Connection Type`, `Routing Info`, `Security`, `User Agent` acoplado a IP Geolocation, `Bulk Lookup`, múltiples idiomas y claves/orígenes extra.[page:1]

## Endpoint recomendado

Usar el endpoint unificado de IP geolocation de la documentación:

```bash
curl "https://api.ipgeolocation.io/v3/ipgeo?apiKey=TU_API_KEY&ip=8.8.8.8"
```

La documentación indica que la API funciona sobre HTTPS y soporta consultas con IPv4 e IPv6.[page:2][page:1]

## Pasos para el agente

1. Crear una cuenta y generar una API key gratuita desde IPGeolocation.[page:1]
2. Guardar la API key en una variable de entorno, por ejemplo `IPGEOLOCATION_API_KEY`, y no exponerla en el frontend.
3. Hacer consultas al endpoint `https://api.ipgeolocation.io/v3/ipgeo` enviando `apiKey` y `ip` como parámetros.[page:2]
4. Consumir solo los bloques compatibles con free: `location`, `country_metadata`, `currency`, `asn` básico y `time_zone`.[page:1]
5. Controlar el consumo de créditos, ya que el free plan tiene 1000 créditos por día y un lookup estándar consume 1 crédito.[page:1]

## Reglas operativas para el agente

- Si no hay IP explícita, usar la IP pública del request del usuario en backend.
- Si el caso de uso solo requiere país, zona horaria o moneda, ignorar campos no necesarios para ahorrar lógica y simplificar la integración.
- No activar módulos de seguridad o abuse en la respuesta unificada porque agregan créditos extra y están orientados a capacidades pagadas.[page:1]
- No usar lookup por dominio en el plan gratis, porque está listado como no disponible.[page:1]

## Ejemplo de implementación en JavaScript

```js
export async function geolocalizarIP(ip) {
  const apiKey = process.env.IPGEOLOCATION_API_KEY;
  const url = new URL('https://api.ipgeolocation.io/v3/ipgeo');
  url.searchParams.set('apiKey', apiKey);
  url.searchParams.set('ip', ip);

  const res = await fetch(url.toString(), {
    headers: { 'Accept': 'application/json' }
  });

  if (!res.ok) {
    throw new Error(`IPGeolocation error: ${res.status}`);
  }

  const data = await res.json();

  return {
    ip: data.ip,
    pais: data.location?.country_name,
    codigoPais: data.location?.country_code2,
    region: data.location?.state_prov,
    ciudad: data.location?.city,
    latitud: data.location?.latitude,
    longitud: data.location?.longitude,
    zonaHoraria: data.time_zone?.name,
    horaLocal: data.time_zone?.current_time,
    moneda: data.currency?.code,
    asn: data.asn?.as_number,
    organizacionASN: data.asn?.organization
  };
}
```

## Prompt/instrucción para otro agente

```txt
Integra IPGeolocation usando exclusivamente el plan gratis. Usa la API key desde variable de entorno `IPGEOLOCATION_API_KEY`. Consulta el endpoint `https://api.ipgeolocation.io/v3/ipgeo` con `apiKey` e `ip`. Solo procesa campos compatibles con free: `location`, `country_metadata`, `currency`, `asn` básico y `time_zone`. No uses features pagadas como domain lookup, hostname, company, security, abuse, bulk lookup, multi-language ni user-agent enriquecido. Considera que el límite del free plan es 1000 créditos por día y que un lookup estándar consume 1 crédito.
```

## Notas de diseño

Para producción, conviene encapsular esta integración detrás de un servicio backend para proteger la API key y aplicar cache por IP cuando el caso de uso lo permita. La página de pricing también señala que el free plan está pensado para testing, prototipos y proyectos de bajo volumen.[page:1]
