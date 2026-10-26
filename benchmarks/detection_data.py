"""Small deliberately imperfect RU/EN fixture set; not a population estimate."""

from dataclasses import dataclass, field

from maskroute import DictionaryEntry

DICTIONARY = (
    DictionaryEntry("Luma Exampleton", "PERSON"),
    DictionaryEntry("Лума Примерова", "PERSON"),
)


@dataclass(frozen=True, repr=False)
class DetectionCase:
    language: str
    text: str
    entities: tuple[tuple[str, str], ...] = field(repr=False)


CASES = (
    DetectionCase("en", "Contact luma@example.invalid.", (("luma@example.invalid", "EMAIL"),)),
    DetectionCase("en", "Phone +1 202 555 0146.", (("+1 202 555 0146", "PHONE"),)),
    DetectionCase("en", "Luma Exampleton needs help.", (("Luma Exampleton", "PERSON"),)),
    DetectionCase("en", "Neri Fictionvale needs help.", (("Neri Fictionvale", "PERSON"),)),
    DetectionCase(
        "en",
        "Email neri [at] example [dot] invalid.",
        (("neri [at] example [dot] invalid", "EMAIL"),),
    ),
    DetectionCase("en", "Public arithmetic result +123456789.", ()),
    DetectionCase("en", "Checked baggage rules please.", ()),
    DetectionCase("ru", "Почта luma@example.invalid.", (("luma@example.invalid", "EMAIL"),)),
    DetectionCase("ru", "Телефон +1 202 555 0146.", (("+1 202 555 0146", "PHONE"),)),
    DetectionCase("ru", "Лума Примерова спрашивает.", (("Лума Примерова", "PERSON"),)),
    DetectionCase("ru", "Нэри Вымыслова спрашивает.", (("Нэри Вымыслова", "PERSON"),)),
    DetectionCase(
        "ru",
        "Адрес neri собака example точка invalid.",
        (("neri собака example точка invalid", "EMAIL"),),
    ),
    DetectionCase("ru", "Публичный номер образца +123456789.", ()),
    DetectionCase("ru", "Какая норма багажа?", ()),
)


def expected_spans(case: DetectionCase) -> set[tuple[int, int, str]]:
    return {
        (case.text.index(value), case.text.index(value) + len(value), kind)
        for value, kind in case.entities
    }
