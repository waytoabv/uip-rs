import { countryName } from './country';

/**
 * Landesflagge zu einem ISO-3166-Alpha-2-Code.
 *
 * Als einzelne SVG-Datei statt über das Stylesheet von flag-icons: dessen CSS
 * bringt alle 272 Flaggen mit und wog gebaut 428 kB, für ein Bild, von dem
 * eine Ansicht eine Handvoll zeigt. So holt der Browser genau die Länder, die
 * gerade auf dem Schirm stehen.
 *
 * Emoji-Flaggen wären billiger, fehlen unter Windows aber vollständig.
 */
export default function CountryFlag(props: { code: string | null | undefined; class?: string }) {
  const code = () => (props.code ?? '').toLowerCase();
  const valid = () => /^[a-z]{2}$/.test(code());
  return (
    <>
      {valid() ? (
        <img
          src={`/flags/${code()}.svg`}
          alt={countryName(props.code)}
          title={countryName(props.code)}
          width="16"
          height="12"
          loading="lazy"
          class={props.class ?? 'inline-block h-3 w-4 rounded-[1px] align-[-1px]'}
        />
      ) : null}
    </>
  );
}
