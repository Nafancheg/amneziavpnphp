<?php
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\TwigFunction;

class View {
  private static ?Environment $twig = null;

  public static function init(string $templatesPath, array $globals = []): void {
    if (!class_exists(Environment::class)) {
      throw new RuntimeException('Twig is not installed. Run composer require twig/twig');
    }
    $loader = new FilesystemLoader($templatesPath);
    self::$twig = new Environment($loader, [
      'cache' => false,
      'autoescape' => 'html',
    ]);

    // Add translation function
    $tFunc = new TwigFunction('t', function (string $key, array $params = []) {
      return Translator::t($key, $params);
    });
    self::$twig->addFunction($tFunc);

    // Add flag emoji function
    $flagFunc = new TwigFunction('getFlag', function (string $langCode) {
      $flags = [
        'en' => '🇬🇧',
        'ru' => '🇷🇺',
        'es' => '🇪🇸',
        'de' => '🇩🇪',
        'fr' => '🇫🇷',
        'zh' => '🇨🇳',
      ];
      return $flags[$langCode] ?? '🌐';
    });
    self::$twig->addFunction($flagFunc);

    // Add globals
    foreach ($globals as $k => $v) self::$twig->addGlobal($k, $v);
  }

  public static function render(string $template, array $vars = []): void {
    if (!self::$twig) throw new RuntimeException('Twig is not initialized');

    if (!array_key_exists('session', $vars)) {
      $vars['session'] = $_SESSION ?? [];
    }

    echo self::$twig->render($template, $vars);

    // Consume one-time flash messages after the response is rendered.
    unset($_SESSION['success_message'], $_SESSION['error_message']);
  }
}